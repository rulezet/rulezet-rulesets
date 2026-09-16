rule tclient_string {
  meta:
    author = "Etienne Maynier"
    email  = "etienne@citizenlab.ca"

  strings:
    $a = "showgodmoney1gz"
    $b = "MDDEFGEGETGIZ"

  condition:
    uint16(0) == 0x5A4D and 2 of them
}