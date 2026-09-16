rule TTP_XOR_WriteProcessMemory_bddf {
  strings:
    $key_bddf = { ea ad [2] d8 8f [2] de ba [2] f0 ba [2] cf a6 }

  condition:
    any of them
}