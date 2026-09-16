rule TTP_XOR_WriteProcessMemory_ddac {
  strings:
    $key_ddac = { 8a de [2] b8 fc [2] be c9 [2] 90 c9 [2] af d5 }

  condition:
    any of them
}