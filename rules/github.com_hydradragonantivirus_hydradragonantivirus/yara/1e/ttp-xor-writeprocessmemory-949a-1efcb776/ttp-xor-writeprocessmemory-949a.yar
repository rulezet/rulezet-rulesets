rule TTP_XOR_WriteProcessMemory_949a {
  strings:
    $key_949a = { c3 e8 [2] f1 ca [2] f7 ff [2] d9 ff [2] e6 e3 }

  condition:
    any of them
}