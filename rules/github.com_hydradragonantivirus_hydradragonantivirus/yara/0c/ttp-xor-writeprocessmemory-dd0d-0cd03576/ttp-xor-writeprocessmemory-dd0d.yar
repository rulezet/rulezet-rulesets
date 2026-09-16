rule TTP_XOR_WriteProcessMemory_dd0d {
  strings:
    $key_dd0d = { 8a 7f [2] b8 5d [2] be 68 [2] 90 68 [2] af 74 }

  condition:
    any of them
}