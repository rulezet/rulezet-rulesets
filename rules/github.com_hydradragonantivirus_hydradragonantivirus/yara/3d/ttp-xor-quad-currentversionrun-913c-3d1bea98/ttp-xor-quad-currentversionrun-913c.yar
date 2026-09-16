rule TTP_XOR_QUAD_CurrentVersionRun_913c {
  strings:
    $key_913c = { c2 53 [2] e6 5d [2] cd 71 [2] e3 53 [2] f7 48 [2] f8 52 [2] e6 4f [2] e4 4e [2] ff 48 [2] e3 4f [2] ff 60 }

  condition:
    any of them
}