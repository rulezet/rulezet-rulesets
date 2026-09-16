rule TTP_XOR_WriteProcessMemory_ddfa {
  strings:
    $key_ddfa = { 8a 88 [2] b8 aa [2] be 9f [2] 90 9f [2] af 83 }

  condition:
    any of them
}