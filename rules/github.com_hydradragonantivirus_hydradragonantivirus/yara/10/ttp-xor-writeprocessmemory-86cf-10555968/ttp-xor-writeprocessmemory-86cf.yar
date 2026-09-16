rule TTP_XOR_WriteProcessMemory_86cf {
  strings:
    $key_86cf = { d1 bd [2] e3 9f [2] e5 aa [2] cb aa [2] f4 b6 }

  condition:
    any of them
}