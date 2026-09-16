rule TTP_XOR_WriteProcessMemory_9acf {
  strings:
    $key_9acf = { cd bd [2] ff 9f [2] f9 aa [2] d7 aa [2] e8 b6 }

  condition:
    any of them
}