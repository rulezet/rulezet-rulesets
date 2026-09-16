rule TTP_XOR_WriteProcessMemory_dd0f {
  strings:
    $key_dd0f = { 8a 7d [2] b8 5f [2] be 6a [2] 90 6a [2] af 76 }

  condition:
    any of them
}