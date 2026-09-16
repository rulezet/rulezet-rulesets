rule TTP_XOR_QUAD_CurrentVersionRun_ffce {
  strings:
    $key_ffce = { ac a1 [2] 88 af [2] a3 83 [2] 8d a1 [2] 99 ba [2] 96 a0 [2] 88 bd [2] 8a bc [2] 91 ba [2] 8d bd [2] 91 92 }

  condition:
    any of them
}