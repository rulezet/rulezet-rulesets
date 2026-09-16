import "math"
rule math_entropy_5 : info statistics {
	meta:
	        description = "Medium entropy - like binary data"

	condition:
		math.entropy(0, filesize) >= 5 and
		math.entropy(0, filesize) < 6
}