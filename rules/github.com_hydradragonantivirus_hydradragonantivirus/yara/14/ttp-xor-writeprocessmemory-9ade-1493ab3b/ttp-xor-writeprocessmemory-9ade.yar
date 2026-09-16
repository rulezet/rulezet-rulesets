rule TTP_XOR_WriteProcessMemory_9ade {
  strings:
    $key_9ade = { cd ac [2] ff 8e [2] f9 bb [2] d7 bb [2] e8 a7 }

  condition:
    any of them
}