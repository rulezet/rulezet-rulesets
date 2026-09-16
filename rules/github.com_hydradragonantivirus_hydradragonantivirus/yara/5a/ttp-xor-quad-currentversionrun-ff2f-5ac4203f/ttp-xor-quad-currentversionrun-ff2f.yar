rule TTP_XOR_QUAD_CurrentVersionRun_ff2f {
  strings:
    $key_ff2f = { ac 40 [2] 88 4e [2] a3 62 [2] 8d 40 [2] 99 5b [2] 96 41 [2] 88 5c [2] 8a 5d [2] 91 5b [2] 8d 5c [2] 91 73 }

  condition:
    any of them
}