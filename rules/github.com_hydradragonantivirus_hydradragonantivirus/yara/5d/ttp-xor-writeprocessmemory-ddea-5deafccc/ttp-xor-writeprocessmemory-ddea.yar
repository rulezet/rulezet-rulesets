rule TTP_XOR_WriteProcessMemory_ddea {
  strings:
    $key_ddea = { 8a 98 [2] b8 ba [2] be 8f [2] 90 8f [2] af 93 }

  condition:
    any of them
}