rule TTP_XOR_WriteProcessMemory_defa {
  strings:
    $key_defa = { 89 88 [2] bb aa [2] bd 9f [2] 93 9f [2] ac 83 }

  condition:
    any of them
}