rule TTP_XOR_QUAD_CurrentVersionRun_ff3f {
  strings:
    $key_ff3f = { ac 50 [2] 88 5e [2] a3 72 [2] 8d 50 [2] 99 4b [2] 96 51 [2] 88 4c [2] 8a 4d [2] 91 4b [2] 8d 4c [2] 91 63 }

  condition:
    any of them
}