rule TTP_XOR_QUAD_CurrentVersionRun_fffd {
  strings:
    $key_fffd = { ac 92 [2] 88 9c [2] a3 b0 [2] 8d 92 [2] 99 89 [2] 96 93 [2] 88 8e [2] 8a 8f [2] 91 89 [2] 8d 8e [2] 91 a1 }

  condition:
    any of them
}