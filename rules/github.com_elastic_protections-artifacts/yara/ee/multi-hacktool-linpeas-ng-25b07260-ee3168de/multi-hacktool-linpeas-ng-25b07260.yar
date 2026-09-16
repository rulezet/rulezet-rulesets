rule Multi_Hacktool_LinPEAS_ng_25b07260 {
    meta:
        author = "Elastic Security"
        id = "25b07260-68ab-4b69-a6bb-a4056014329b"
        fingerprint = "0ec6241c4dba1e806c654056257fce7ddd67a4b2cd36d3e19a2c486b5befb7aa"
        creation_date = "2022-12-21"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the container module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "593333df3a1e109c73e8823e3929d52a7fc79a3064eb62004f33f11daca10d0b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $container_0 = "find / -maxdepth 3 -name '*dockerenv*'" base64
        $container_1 = "/kubepod" base64
        $container_2 = "container=podman" base64
        $container_3 = "$(grep -a 'container=' /proc/1/environ" base64
        $container_4 = "You have write permissions over interesting socket" base64
        $container_5 = "Am I Containered?" base64
        $container_6 = "release_agent breakout" base64
        $container_7 = "DoS via panic_" base64
        $container_8 = "Container Capabilities" base64
        $container_9 = "$(command -v capsh)" base64
    condition:
        5 of them
}