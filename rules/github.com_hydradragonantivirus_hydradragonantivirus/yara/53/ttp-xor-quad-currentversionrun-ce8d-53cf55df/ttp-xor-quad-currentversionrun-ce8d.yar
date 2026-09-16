rule TTP_XOR_QUAD_CurrentVersionRun_ce8d {
  strings:
    $key_ce8d = { 9d e2 [2] b9 ec [2] 92 c0 [2] bc e2 [2] a8 f9 [2] a7 e3 [2] b9 fe [2] bb ff [2] a0 f9 [2] bc fe [2] a0 d1 }

  condition:
    any of them
}