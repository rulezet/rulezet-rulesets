rule dropper_strings {
  meta:
    author = "Etienne Maynier"
    email  = "etienne@citizenlab.ca"

  strings:
    $a = "bitsadmin /canceft\\windows\\currebitsadmin /addfibitsadmin /Resumbitsadmin /SetNosoftware"
    $b = "\\microsotifyCmdLine %s rle %s c:\\windowsbitsadmin /creat\\system32\\net.ex"
    $c = "rundll32.exe %s Main"
    $d = "d1fasg34"
    $e = "FindResource %s error"

  condition:
    uint16(0) == 0x5A4D and 2 of them
}