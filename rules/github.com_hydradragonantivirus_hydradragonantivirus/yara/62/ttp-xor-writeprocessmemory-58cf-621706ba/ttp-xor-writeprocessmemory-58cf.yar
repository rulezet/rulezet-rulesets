rule TTP_XOR_WriteProcessMemory_58cf {
  strings:
    $key_58cf = { 0f bd [2] 3d 9f [2] 3b aa [2] 15 aa [2] 2a b6 }

  condition:
    any of them
}