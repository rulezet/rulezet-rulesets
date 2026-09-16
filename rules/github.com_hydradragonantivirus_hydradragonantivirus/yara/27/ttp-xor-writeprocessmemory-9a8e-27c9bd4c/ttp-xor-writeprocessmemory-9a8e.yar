rule TTP_XOR_WriteProcessMemory_9a8e {
  strings:
    $key_9a8e = { cd fc [2] ff de [2] f9 eb [2] d7 eb [2] e8 f7 }

  condition:
    any of them
}