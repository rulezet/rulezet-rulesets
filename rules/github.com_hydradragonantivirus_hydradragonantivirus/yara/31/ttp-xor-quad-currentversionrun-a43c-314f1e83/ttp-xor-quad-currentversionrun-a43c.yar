rule TTP_XOR_QUAD_CurrentVersionRun_a43c {
  strings:
    $key_a43c = { f7 53 [2] d3 5d [2] f8 71 [2] d6 53 [2] c2 48 [2] cd 52 [2] d3 4f [2] d1 4e [2] ca 48 [2] d6 4f [2] ca 60 }

  condition:
    any of them
}