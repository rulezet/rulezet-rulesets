rule TTP_XOR_WriteProcessMemory_f9bf {
  strings:
    $key_f9bf = { ae cd [2] 9c ef [2] 9a da [2] b4 da [2] 8b c6 }

  condition:
    any of them
}