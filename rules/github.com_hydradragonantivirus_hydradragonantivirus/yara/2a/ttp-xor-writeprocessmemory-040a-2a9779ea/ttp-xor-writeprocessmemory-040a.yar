rule TTP_XOR_WriteProcessMemory_040a {
  strings:
    $key_040a = { 53 78 [2] 61 5a [2] 67 6f [2] 49 6f [2] 76 73 }

  condition:
    any of them
}