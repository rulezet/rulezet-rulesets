rule TTP_XOR_QUAD_CurrentVersionRun_e0c1 {
  strings:
    $key_e0c1 = { b3 ae [2] 97 a0 [2] bc 8c [2] 92 ae [2] 86 b5 [2] 89 af [2] 97 b2 [2] 95 b3 [2] 8e b5 [2] 92 b2 [2] 8e 9d }

  condition:
    any of them
}