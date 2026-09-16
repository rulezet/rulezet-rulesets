rule TTP_XOR_WriteProcessMemory_fadf {
  strings:
    $key_fadf = { ad ad [2] 9f 8f [2] 99 ba [2] b7 ba [2] 88 a6 }

  condition:
    any of them
}