rule TTP_XOR_QUAD_CurrentVersionRun_4bce {
  strings:
    $key_4bce = { 18 a1 [2] 3c af [2] 17 83 [2] 39 a1 [2] 2d ba [2] 22 a0 [2] 3c bd [2] 3e bc [2] 25 ba [2] 39 bd [2] 25 92 }

  condition:
    any of them
}