rule TTP_XOR_QUAD_CurrentVersionRun_ff3c {
  strings:
    $key_ff3c = { ac 53 [2] 88 5d [2] a3 71 [2] 8d 53 [2] 99 48 [2] 96 52 [2] 88 4f [2] 8a 4e [2] 91 48 [2] 8d 4f [2] 91 60 }

  condition:
    any of them
}