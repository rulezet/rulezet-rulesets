rule TTP_XOR_QUAD_CurrentVersionRun_3bce {
  strings:
    $key_3bce = { 68 a1 [2] 4c af [2] 67 83 [2] 49 a1 [2] 5d ba [2] 52 a0 [2] 4c bd [2] 4e bc [2] 55 ba [2] 49 bd [2] 55 92 }

  condition:
    any of them
}