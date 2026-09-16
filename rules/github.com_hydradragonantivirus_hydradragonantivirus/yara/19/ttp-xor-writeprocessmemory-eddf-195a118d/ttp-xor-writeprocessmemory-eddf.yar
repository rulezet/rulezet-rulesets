rule TTP_XOR_WriteProcessMemory_eddf {
  strings:
    $key_eddf = { ba ad [2] 88 8f [2] 8e ba [2] a0 ba [2] 9f a6 }

  condition:
    any of them
}