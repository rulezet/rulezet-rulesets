rule FFT_and_FHT_routines_costab__flt32___32_lil_32_ {
  strings:
    $a0 = { 5e 83 6c 3f 15 ef c3 3e 6d c4 7e 3f 36 bd c8 3d 43 ec 7f 3f b0 0a c9 3c c4 fe 7f 3f 88 0f c9 3b }

  condition:
    $a0
}