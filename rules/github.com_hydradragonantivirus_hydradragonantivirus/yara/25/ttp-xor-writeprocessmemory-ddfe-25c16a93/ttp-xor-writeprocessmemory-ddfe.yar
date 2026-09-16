rule TTP_XOR_WriteProcessMemory_ddfe {
  strings:
    $key_ddfe = { 8a 8c [2] b8 ae [2] be 9b [2] 90 9b [2] af 87 }

  condition:
    any of them
}