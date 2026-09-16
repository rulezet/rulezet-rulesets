rule TTP_XOR_WriteProcessMemory_0382 {
  strings:
    $key_0382 = { 54 f0 [2] 66 d2 [2] 60 e7 [2] 4e e7 [2] 71 fb }

  condition:
    any of them
}