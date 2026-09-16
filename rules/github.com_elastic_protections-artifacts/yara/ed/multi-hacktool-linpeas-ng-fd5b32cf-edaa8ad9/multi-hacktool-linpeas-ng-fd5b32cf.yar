rule Multi_Hacktool_LinPEAS_ng_fd5b32cf {
    meta:
        author = "Elastic Security"
        id = "fd5b32cf-b96c-41a1-8119-5a688a1e2ebf"
        fingerprint = "d19f8c7ed050f6c45e613aa70aa5ddd1dc0b7a7d1309d31bc2b5eb969fff6868"
        creation_date = "2022-12-21"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the container module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "cc3e69418622499a21248c762373642eb2a2b1073767f22f0dd0f65d0def94a5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $container_0 = "find / -maxdepth 3 -name '*dockerenv*'"
        $container_1 = "/kubepod"
        $container_2 = "container=podman"
        $container_3 = "$(grep -a 'container=' /proc/1/environ"
        $container_4 = "You have write permissions over interesting socket"
        $container_5 = "Am I Containered?"
        $container_6 = "release_agent breakout"
        $container_7 = "DoS via panic_"
        $container_8 = "Container Capabilities"
        $container_9 = "$(command -v capsh)"
    condition:
        5 of them
}