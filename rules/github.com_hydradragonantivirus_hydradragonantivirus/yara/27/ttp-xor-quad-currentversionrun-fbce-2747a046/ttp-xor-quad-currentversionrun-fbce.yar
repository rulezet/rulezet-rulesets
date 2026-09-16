rule TTP_XOR_QUAD_CurrentVersionRun_fbce {
  strings:
    $key_fbce = { a8 a1 [2] 8c af [2] a7 83 [2] 89 a1 [2] 9d ba [2] 92 a0 [2] 8c bd [2] 8e bc [2] 95 ba [2] 89 bd [2] 95 92 }

  condition:
    any of them
}