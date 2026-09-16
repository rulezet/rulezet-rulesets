rule TTP_XOR_QUAD_CurrentVersionRun_3841 {
  strings:
    $key_3841 = { 6b 2e [2] 4f 20 [2] 64 0c [2] 4a 2e [2] 5e 35 [2] 51 2f [2] 4f 32 [2] 4d 33 [2] 56 35 [2] 4a 32 [2] 56 1d }

  condition:
    any of them
}