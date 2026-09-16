rule TTP_XOR_WriteProcessMemory_ddec {
  strings:
    $key_ddec = { 8a 9e [2] b8 bc [2] be 89 [2] 90 89 [2] af 95 }

  condition:
    any of them
}