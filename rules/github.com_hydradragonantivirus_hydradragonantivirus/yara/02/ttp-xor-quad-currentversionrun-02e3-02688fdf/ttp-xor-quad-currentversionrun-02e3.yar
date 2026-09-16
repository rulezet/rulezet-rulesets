rule TTP_XOR_QUAD_CurrentVersionRun_02e3 {
  strings:
    $key_02e3 = { 51 8c [2] 75 82 [2] 5e ae [2] 70 8c [2] 64 97 [2] 6b 8d [2] 75 90 [2] 77 91 [2] 6c 97 [2] 70 90 [2] 6c bf }

  condition:
    any of them
}