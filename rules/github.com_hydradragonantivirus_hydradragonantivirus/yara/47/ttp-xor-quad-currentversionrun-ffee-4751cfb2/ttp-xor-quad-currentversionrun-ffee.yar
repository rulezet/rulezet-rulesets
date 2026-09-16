rule TTP_XOR_QUAD_CurrentVersionRun_ffee {
  strings:
    $key_ffee = { ac 81 [2] 88 8f [2] a3 a3 [2] 8d 81 [2] 99 9a [2] 96 80 [2] 88 9d [2] 8a 9c [2] 91 9a [2] 8d 9d [2] 91 b2 }

  condition:
    any of them
}