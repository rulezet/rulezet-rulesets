rule TTP_XOR_QUAD_CurrentVersionRun_fffe {
  strings:
    $key_fffe = { ac 91 [2] 88 9f [2] a3 b3 [2] 8d 91 [2] 99 8a [2] 96 90 [2] 88 8d [2] 8a 8c [2] 91 8a [2] 8d 8d [2] 91 a2 }

  condition:
    any of them
}