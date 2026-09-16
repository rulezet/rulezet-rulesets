rule payload_wab32res_strings {
  meta:
    author = "Etienne Maynier"
    email  = "etienne@citizenlab.ca"

  strings:
    $a1 = "%02d%02d%02d%02d%02d%03d"
    $a2 = "459B2-3311-54C3- /Processid:{712"
    $a3 = "CreateProcess %s"
    $a4 = "FakeRun.dll"
    $a5 = "Release\\FakeRun.pdb"

  condition:
    uint16(0) == 0x5A4D and 2 of them
}