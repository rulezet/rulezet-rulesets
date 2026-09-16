rule TTP_XOR_QUAD_CurrentVersionRun_ffec {
  strings:
    $key_ffec = { ac 83 [2] 88 8d [2] a3 a1 [2] 8d 83 [2] 99 98 [2] 96 82 [2] 88 9f [2] 8a 9e [2] 91 98 [2] 8d 9f [2] 91 b0 }

  condition:
    any of them
}