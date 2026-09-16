rule TTP_XOR_WriteProcessMemory_88cf {
  strings:
    $key_88cf = { df bd [2] ed 9f [2] eb aa [2] c5 aa [2] fa b6 }

  condition:
    any of them
}