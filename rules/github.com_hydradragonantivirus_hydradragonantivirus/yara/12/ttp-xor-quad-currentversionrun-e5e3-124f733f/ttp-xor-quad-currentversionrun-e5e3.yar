rule TTP_XOR_QUAD_CurrentVersionRun_e5e3 {
  strings:
    $key_e5e3 = { b6 8c [2] 92 82 [2] b9 ae [2] 97 8c [2] 83 97 [2] 8c 8d [2] 92 90 [2] 90 91 [2] 8b 97 [2] 97 90 [2] 8b bf }

  condition:
    any of them
}