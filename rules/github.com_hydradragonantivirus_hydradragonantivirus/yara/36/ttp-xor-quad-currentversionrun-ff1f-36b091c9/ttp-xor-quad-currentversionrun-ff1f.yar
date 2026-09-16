rule TTP_XOR_QUAD_CurrentVersionRun_ff1f {
  strings:
    $key_ff1f = { ac 70 [2] 88 7e [2] a3 52 [2] 8d 70 [2] 99 6b [2] 96 71 [2] 88 6c [2] 8a 6d [2] 91 6b [2] 8d 6c [2] 91 43 }

  condition:
    any of them
}