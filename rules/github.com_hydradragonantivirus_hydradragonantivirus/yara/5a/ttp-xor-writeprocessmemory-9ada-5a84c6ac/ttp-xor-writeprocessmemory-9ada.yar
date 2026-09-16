rule TTP_XOR_WriteProcessMemory_9ada {
  strings:
    $key_9ada = { cd a8 [2] ff 8a [2] f9 bf [2] d7 bf [2] e8 a3 }

  condition:
    any of them
}