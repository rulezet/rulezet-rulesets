rule PEiD_00361_CALS_Raster_graphics_format_ {
  meta:
    description = "[CALS Raster graphics format]"
    ep_only     = "false"

  strings:
    $a = "srcdocid: "

  condition:
    $a
}