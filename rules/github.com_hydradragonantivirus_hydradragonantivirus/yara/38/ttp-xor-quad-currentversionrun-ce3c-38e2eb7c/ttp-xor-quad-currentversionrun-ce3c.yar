rule TTP_XOR_QUAD_CurrentVersionRun_ce3c {
  strings:
    $key_ce3c = { 9d 53 [2] b9 5d [2] 92 71 [2] bc 53 [2] a8 48 [2] a7 52 [2] b9 4f [2] bb 4e [2] a0 48 [2] bc 4f [2] a0 60 }

  condition:
    any of them
}