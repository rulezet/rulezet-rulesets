rule TTP_XOR_QUAD_CurrentVersionRun_e0c0 {
  strings:
    $key_e0c0 = { b3 af [2] 97 a1 [2] bc 8d [2] 92 af [2] 86 b4 [2] 89 ae [2] 97 b3 [2] 95 b2 [2] 8e b4 [2] 92 b3 [2] 8e 9c }

  condition:
    any of them
}