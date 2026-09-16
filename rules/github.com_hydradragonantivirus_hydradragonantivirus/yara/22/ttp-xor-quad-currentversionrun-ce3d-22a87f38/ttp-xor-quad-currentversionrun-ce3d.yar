rule TTP_XOR_QUAD_CurrentVersionRun_ce3d {
  strings:
    $key_ce3d = { 9d 52 [2] b9 5c [2] 92 70 [2] bc 52 [2] a8 49 [2] a7 53 [2] b9 4e [2] bb 4f [2] a0 49 [2] bc 4e [2] a0 61 }

  condition:
    any of them
}