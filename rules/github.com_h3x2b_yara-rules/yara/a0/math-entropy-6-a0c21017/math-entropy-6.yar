import "math"
rule math_entropy_6 : info statistics {
	meta:
	        description = "High entropy - like binary code or base64 encoded random stream"

	condition:
		math.entropy(0, filesize) >= 6 and
		math.entropy(0, filesize) < 7
}