rule TTP_XOR_WriteProcessMemory_ddbf {
  strings:
    $key_ddbf = { 8a cd [2] b8 ef [2] be da [2] 90 da [2] af c6 }

  condition:
    any of them
}